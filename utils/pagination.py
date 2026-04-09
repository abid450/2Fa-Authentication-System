from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class StandardResultSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            'status' : 'success',
            'count' : self.page.paginator.count,
            'total_page' : self.page.paginator.num_pages,
            'current_page' : self.page.number,
            'next' : self.get_next_link(),
            'previous' : self.get_previous_link(),
            'results' : data
        })
    

class SmallResultPagination(PageNumberPagination):
    page_size = 5
    page_size_query_param = 'page_size'
    max_page_size = 20

    def get_paginated_response(self, data):
        return Response({
            'status' : 'success',
            'count' : self.page.paginator.count,
            'results' : data
        })